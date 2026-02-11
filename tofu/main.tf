# Root orchestrator — calls child modules

module "example" {
  source = "./modules/example"

  project_name = var.project_name
  environment  = var.environment
}
