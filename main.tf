provider "aws" {
  region = "ap-southeast-2"  # Change this to your desired AWS region
}

resource "aws_iam_role" "lambda_execution_role" {
  name = "lambda_execution_role"
  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  # AmazonS3ObjectLambdaExecutionRolePolicy
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid: ""
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
  tags = {
    tag-key = "Lambda-Execution-Role"
  }
}

# View only access policy
resource "aws_iam_policy" "view_only_access" {
  name        = "ViewOnlyAccessPolicy"
  description = "AWS-managed policy for ViewOnlyAccess"
  policy      = data.aws_iam_policy_document.view_only_access.json
}

data "aws_iam_policy_document" "view_only_access" {
  version = "2012-10-17"
  
  statement {
    actions   = ["s3:ListBucket"]
    effect    = "Allow"
    resources = ["*"]
  }

  statement {
    actions   = ["s3:GetObject"]
    effect    = "Allow"
    resources = ["*"]
  }
}


resource "aws_iam_role_policy_attachment" "attach_view_only_access" {
  policy_arn = aws_iam_policy.view_only_access.arn
  role       = aws_iam_role.lambda_execution_role.name
}

# Custom managed policy for my buckets access
resource "aws_iam_policy" "my_buckets_access_policy" {
  name        = "my-buckets-access-policy"
  description = "Custom managed policy for my buckets access"
  policy      = data.aws_iam_policy_document.my_buckets_access_policy.json
}

data "aws_iam_policy_document" "my_buckets_access_policy" {
  version = "2012-10-17"

  statement {
    actions   = ["s3:ListBucket", "s3:GetObject", "s3:PutObject"]
    effect    = "Allow"
    resources = ["arn:aws:s3:::restricted-bucket-var/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = ["987654321898"]
    }
  }
}


resource "aws_iam_role_policy_attachment" "attach_my_buckets_access_policy" {
  policy_arn = aws_iam_policy.my_buckets_access_policy.arn
  role       = aws_iam_role.lambda_execution_role.name
}

resource "aws_s3_bucket" "example" {
  bucket = "restricted-bucket-var"
}

resource "aws_s3_bucket_ownership_controls" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "example" {
  depends_on = [aws_s3_bucket_ownership_controls.example]

  bucket = aws_s3_bucket.example.id
  acl    = "private"
}

resource "aws_iam_role" "example_role" {
  name = "bucket_role_var"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::123456789012:role/<bucket_role_var>"  # Replace <bucket_role_var> with the actual role name
        }
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "attach_bucket_policy" {
  bucket = aws_iam_role.example_role.name  # Reference the S3 bucket created in the S3 bucket module
  policy = data.aws_iam_policy_document.my_buckets_access_policy.json
}

resource "aws_iam_role_policy_attachment" "attach_my_buckets_access_policy_s3_bucket" {
  policy_arn = aws_iam_policy.my_buckets_access_policy.arn
  role       = aws_iam_role.example_role.name
}
