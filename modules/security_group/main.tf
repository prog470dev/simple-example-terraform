variable "name" {}
variable "vpc_id" {}
# 通信を許可するポート（インバウンド）
variable "port" {}
# 通信を許可するCIDRブロック（インバウンド）
variable "cidr_blocks" {
  type = list(string)
}

resource "aws_security_group" "default" {
  name   = var.name
  vpc_id = var.vpc_id
}

# インバウンド
resource "aws_security_group_rule" "ingress" {
  type              = "ingress"
  from_port         = var.port
  to_port           = var.port
  protocol          = "tcp"
  cidr_blocks       = var.cidr_blocks
  security_group_id = aws_security_group.default.id
}

# アウトバウンド
resource "aws_security_group_rule" "ingress_default" {
  type = "egress"
  # protocolを-1にする場合はportを0にする必要がある
  from_port         = 0
  to_port           = 0
  protocol          = "-1" # all
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.default.id
}

output "security_group_id" {
  value = aws_security_group.default.id
}
