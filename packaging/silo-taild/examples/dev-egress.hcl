settings {
  default_action = "deny"
}
endpoint "https" "github" {
  hosts = ["github.com", "api.github.com", "*.githubusercontent.com"]
}
endpoint "https" "crates" {
  hosts = ["crates.io", "static.crates.io", "index.crates.io"]
}
credential "bearer_token" "github-api" {
  endpoint = https.github
}
rule "github" {
  endpoints = [https.github]
  credential = bearer_token.github-api
  verdict = "allow"
}
rule "crates" {
  endpoints = [https.crates]
  verdict = "allow"
}
