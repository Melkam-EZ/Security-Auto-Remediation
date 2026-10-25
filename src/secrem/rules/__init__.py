"""The rule catalogue. Adding a rule = write a class, add it here, add it to the policy file."""
from .ec2 import Imdsv2, OpenSecurityGroup, UnencryptedVolume
from .iam_rds import PublicDatabase, StaleAccessKey, UserWithoutMfa
from .s3 import PublicAccessBlock, SslOnly

ALL = [PublicAccessBlock, SslOnly, OpenSecurityGroup, Imdsv2, UnencryptedVolume,
       StaleAccessKey, UserWithoutMfa, PublicDatabase]
CATALOG = {cls.id: cls for cls in ALL}


def build(policy):
    """Instantiate the rules the policy lists, each with its configured parameters."""
    return {rid: CATALOG[rid](policy.params(rid)) for rid in policy.rule_ids()}
