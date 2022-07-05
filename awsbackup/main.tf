locals {
  stack_name = "awsbackup_organization_managed"
}

data "aws_region" "current" {}
data "aws_caller_identity" "current_session" {}

resource "aws_iam_role" "backup_role" {
  count = data.aws_region.current.name == var.main_region ? 1 : 0 # To be deployed once in a single region
  name  = "${var.resource_prefix}_backup_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
  ]

  tags = {
    "${var.tag_key_scp_protection}" = "${var.tag_value_scp_protection}"
  }
}

resource "aws_kms_key" "backup_vault_key" {
  description         = "KMS Key for AWS Backup Vault"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Sid" : "Enable IAM User Permissions"
        Action   = "kms:*"
        Effect   = "Allow"
        Resource = "*"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current_session.account_id}:root"
        }
      },
      {
        "Sid" : "Allow Use of the Key from AWS Backup Copy Account"
        Action = [
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext"
        ]
        Effect   = "Allow"
        Resource = "*"
        Principal = {
          AWS = "arn:aws:iam::${var.copy_account_id}:root"
        }
      },
      {
        "Sid" : "Allow attachment of persistent resources from AWS Backup Copy Account"
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrants",
        ]
        Effect   = "Allow"
        Resource = "*"
        Principal = {
          AWS = "arn:aws:iam::${var.copy_account_id}:root"
        }
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }
        }
      }
    ]
  })
  tags = {
    "${var.tag_key_scp_protection}" = "${var.tag_value_scp_protection}"
  }
}

resource "aws_kms_alias" "backup_vault_key_alias" {
  name          = "alias/backup/${var.resource_prefix}_backup_vault"
  target_key_id = aws_kms_key.backup_vault_key.arn
}

resource "aws_backup_vault" "backup_vault" {
  name        = "${var.resource_prefix}_backup_vault"
  kms_key_arn = aws_kms_key.backup_vault_key.arn
}

resource "aws_iam_role" "backup_notification_role" {
  count = (data.aws_region.current.name == var.main_region) && var.install_notifications ? 1 : 0 # To be deployed once in a single region and only if notifications are enabled
  name  = "${var.resource_prefix}_backup_notifications_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  inline_policy {
    name = "backup_notifications_inline_policy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Resource = "arn:aws:logs:*:${data.aws_caller_identity.current_session.account_id}:log-group:/aws/lambda/${var.resource_prefix}_backup_notifications_forwarder:*"
          Action = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
          ]
          Effect = "Allow"
        },
        {
          Resource = "arn:aws:sns:${var.main_region}:${var.main_account_id}:${var.resource_prefix}_aggregate_backup_notifications_topic"
          Action   = "sns:publish"
          Effect   = "Allow"
        }
        ]
    })
  }

  tags = {
    "${var.tag_key_scp_protection}" = "${var.tag_value_scp_protection}"
  }
}

module "backup_notification_forwarder" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git"

  count         = var.install_notifications ? 1 : 0
  function_name = "${var.resource_prefix}_backup_notifications_forwarder"
  description   = "SNS message forwarding function for aggregating backup notifications."
  handler       = "backup_notifications_forwarder.lambda_handler"
  runtime       = "python3.8"
  publish       = true
  timeout       = 60
  memory_size   = 128
  create_role   = false
  lambda_role   = data.aws_region.current.name == var.main_region ? aws_iam_role.backup_notification_role[0].arn : "arn:aws:iam::${data.aws_caller_identity.current_session.account_id}:role/${var.resource_prefix}_backup_notifications_role"

  source_path = "../Py/backup_notifications_forwarder.py"

  environment_variables = {
    sns_arn     = "arn:aws:sns:${var.main_region}:${var.main_account_id}:${var.resource_prefix}_aggregate_backup_notifications_topic"
    main_region = var.main_region
  }

  allowed_triggers = {
    BackupNotificationsTopic = {
      service    = "sns"
      source_arn = aws_sns_topic.backup_notifications_topic[0].arn
    }
  }

  tags = {
    "${var.tag_key_scp_protection}" = "${var.tag_value_scp_protection}"
  }
}

resource "aws_sns_topic" "backup_notifications_topic" {
  count        = var.install_notifications ? 1 : 0
  name         = "${var.resource_prefix}_backup_notifications_topic"
  display_name = "${var.resource_prefix}_backup_notifications_topic"

  tags = {
    "${var.tag_key_scp_protection}" = "${var.tag_value_scp_protection}"
  }
}

data "aws_iam_policy_document" "backup_notifications_topic_policy_document" {
  count = var.install_notifications ? 1 : 0
  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission"
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        data.aws_caller_identity.current_session.account_id
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      aws_sns_topic.backup_notifications_topic[0].arn,
    ]

    sid = "__default_statement_ID"
  }

  statement {
    actions = [
      "SNS:Publish",
    ]

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [
      aws_sns_topic.backup_notifications_topic[0].arn,
    ]

    sid = "TrustCWEToPublishEventsToMyTopic"
  }

}

resource "aws_sns_topic_policy" "backup_notifications_topic_policy" {
  count  = var.install_notifications ? 1 : 0
  arn    = aws_sns_topic.backup_notifications_topic[0].arn
  policy = data.aws_iam_policy_document.backup_notifications_topic_policy_document[0].json
}

resource "aws_sns_topic_subscription" "notifications_aggregate_topic_subscription" {
  count     = var.install_notifications ? 1 : 0
  topic_arn = aws_sns_topic.backup_notifications_topic[0].arn
  protocol  = "lambda"
  endpoint  = module.backup_notification_forwarder[0].lambda_function_arn
}

resource "aws_cloudwatch_event_rule" "backup_job_event" {
  count       = var.install_notifications ? 1 : 0
  name        = "${var.resource_prefix}_backup_job_event"
  description = "AWS Backup notification Rule for backup jobs"

  event_pattern = <<EOF
{
  "source": ["aws.backup"],
  "detail-type": ["Backup Job State Change", "Copy Job State Change"],
  "detail": {"state": ["ABORTED", "FAILED", "EXPIRED"]}
}
EOF
}

resource "aws_cloudwatch_event_target" "backup_job_event_target" {
  count       = var.install_notifications ? 1 : 0
  rule      = aws_cloudwatch_event_rule.backup_job_event[0].name
  target_id = "Target_SNS_Topic"
  arn       = aws_sns_topic.backup_notifications_topic[0].arn
}
