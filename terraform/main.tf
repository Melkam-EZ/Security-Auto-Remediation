data "aws_caller_identity" "me" {}

locals {
  fn_name = "${var.name}-remediator"
  # Everything we react to in real time: the API calls that can create or loosen the things our rules watch.
  watched = {
    s3  = { source = "s3.amazonaws.com", events = ["CreateBucket", "PutBucketPublicAccessBlock", "DeletePublicAccessBlock", "PutBucketPolicy", "DeleteBucketPolicy"] }
    ec2 = { source = "ec2.amazonaws.com", events = ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules", "RunInstances", "ModifyInstanceMetadataOptions"] }
    rds = { source = "rds.amazonaws.com", events = ["CreateDBInstance", "ModifyDBInstance"] }
  }
}

# ---- state: one item per (rule, resource) ------------------------------------------------------------
resource "aws_dynamodb_table" "findings" {
  name         = "${var.name}-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }
  attribute {
    name = "state"
    type = "S"
  }
  attribute {
    name = "updated_epoch"
    type = "N"
  }

  global_secondary_index {
    name            = "by_state"
    hash_key        = "state"
    range_key       = "updated_epoch"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "expires_epoch"
    enabled        = true
  }
  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled = true
  }
}

# ---- notifications -----------------------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name              = "${var.name}-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = toset(var.notify_emails)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# ---- the function -------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "fn" {
  name              = "/aws/lambda/${local.fn_name}"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "remediator" {
  name = "${var.name}-remediator"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "remediator" {
  name = "least-privilege"
  role = aws_iam_role.remediator.id
  policy = templatefile("${path.module}/policies/remediator.json", {
    table_arn     = aws_dynamodb_table.findings.arn
    topic_arn     = aws_sns_topic.alerts.arn
    log_group_arn = aws_cloudwatch_log_group.fn.arn
  })
}

# The zip holds the secrem/ package and policy/remediation-policy.json (build with scripts/build_zip.sh).
data "archive_file" "fn" {
  type        = "zip"
  source_dir  = "${path.module}/build"
  output_path = "${path.module}/secrem.zip"
}

resource "aws_lambda_function" "fn" {
  function_name    = local.fn_name
  role             = aws_iam_role.remediator.arn
  runtime          = "python3.12"
  handler          = "secrem.handler.lambda_handler"
  filename         = data.archive_file.fn.output_path
  source_code_hash = data.archive_file.fn.output_base64sha256
  timeout          = 300
  memory_size      = 256
  # One at a time: two copies fixing the same account at once is how guards get bypassed.
  reserved_concurrent_executions = 1

  environment {
    variables = {
      FINDINGS_TABLE      = aws_dynamodb_table.findings.name
      TOPIC_ARN           = aws_sns_topic.alerts.arn
      DRY_RUN             = tostring(var.dry_run)
      REGIONS             = var.region
      APPROVERS           = join(",", var.approver_arns)
      REMEDIATOR_ROLE_ARN = aws_iam_role.remediator.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.fn, aws_iam_role_policy.remediator]
}

# ---- approvals: an HTTPS endpoint that only accepts requests signed by an AWS identity ---------------
resource "aws_lambda_function_url" "approvals" {
  function_name      = aws_lambda_function.fn.function_name
  authorization_type = "AWS_IAM"
}

# ---- triggers ---------------------------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "changes" {
  for_each    = local.watched
  name        = "${var.name}-${each.key}-changes"
  description = "Real-time: ${each.key} API calls that may create a misconfiguration"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail        = { eventSource = [each.value.source], eventName = each.value.events }
  })
}

resource "aws_cloudwatch_event_target" "changes" {
  for_each = local.watched
  rule     = aws_cloudwatch_event_rule.changes[each.key].name
  arn      = aws_lambda_function.fn.arn
}

resource "aws_lambda_permission" "changes" {
  for_each      = local.watched
  statement_id  = "events-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.changes[each.key].arn
}

resource "aws_cloudwatch_event_rule" "scan" {
  name                = "${var.name}-scheduled-scan"
  description         = "Full scan: catches drift, old resources and anything the events missed"
  schedule_expression = var.scan_schedule
}

resource "aws_cloudwatch_event_target" "scan" {
  rule = aws_cloudwatch_event_rule.scan.name
  arn  = aws_lambda_function.fn.arn
}

resource "aws_lambda_permission" "scan" {
  statement_id  = "events-scan"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scan.arn
}

# ---- optional trail: guarantees management events exist for the real-time path -------------------------
resource "aws_s3_bucket" "trail" {
  count         = var.enable_trail ? 1 : 0
  bucket        = "${var.name}-trail-${data.aws_caller_identity.me.account_id}-${var.region}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  count                   = var.enable_trail ? 1 : 0
  bucket                  = aws_s3_bucket.trail[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "trail" {
  count  = var.enable_trail ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "AclCheck", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:GetBucketAcl", Resource = aws_s3_bucket.trail[0].arn },
      { Sid = "Write", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:PutObject",
      Resource = "${aws_s3_bucket.trail[0].arn}/AWSLogs/${data.aws_caller_identity.me.account_id}/*", Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } } },
      { Sid = "TlsOnly", Effect = "Deny", Principal = "*", Action = "s3:*", Resource = [aws_s3_bucket.trail[0].arn, "${aws_s3_bucket.trail[0].arn}/*"], Condition = { Bool = { "aws:SecureTransport" = "false" } } }
    ]
  })
}

resource "aws_cloudtrail" "this" {
  count                         = var.enable_trail ? 1 : 0
  name                          = "${var.name}-trail"
  s3_bucket_name                = aws_s3_bucket.trail[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.trail]
}

# ---- alarms: the platform watching itself ------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${var.name}-function-errors"
  alarm_description   = "The remediator itself crashed"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.fn.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "guard" {
  alarm_name          = "${var.name}-guard-tripped"
  alarm_description   = "Too many automatic fixes at once: something unusual is happening"
  namespace           = "SecRem"
  metric_name         = "GuardTripped"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "failed" {
  alarm_name          = "${var.name}-remediation-failed"
  alarm_description   = "A fix errored or did not make the resource compliant"
  namespace           = "SecRem"
  metric_name         = "RemediationFailed"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}
