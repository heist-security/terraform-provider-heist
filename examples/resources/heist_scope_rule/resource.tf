resource "heist_scope_rule" "block_admin" {
  pattern = "app.example.com/admin/**"
  action  = "BLOCK"
}

resource "heist_scope_rule" "allow_api" {
  pattern = "api.example.com/**"
  action  = "ALLOW"
}
