output "approval_url" {
  description = "export SECREM_URL=<this>, then use scripts/secrem"
  value       = aws_lambda_function_url.approvals.function_url
}

output "function_name" {
  value = aws_lambda_function.fn.function_name
}

output "findings_table" {
  value = aws_dynamodb_table.findings.name
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "dry_run" {
  value = var.dry_run
}
