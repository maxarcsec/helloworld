resource "alicloud_security_group_rule" "arcsec_boundary_canary" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "22/22"
  cidr_ip           = "0.0.0.0/0"
  security_group_id = "sg-arcsec-synthetic"
}
