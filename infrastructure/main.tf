
terraform {
  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.64"
    }
  }

  backend "s3" {
    key                         = "opentofu.tfstate"
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    use_path_style              = true
  }

  required_version = ">= 0.13"
}

locals {
  project_id = "852d1eb2-8f95-4623-93e2-25f73680210a"
}

provider "scaleway" {}

resource "scaleway_domain_registration" "test" {
  domain_names      = ["jwkserve.com"]
  duration_in_years = 1
  project_id        = local.project_id
  dnssec            = true

  owner_contact {
    legal_form                  = "individual"
    firstname                   = "Sebastian"
    lastname                    = "Mueller"
    email                       = var.owner_contact.email
    phone_number                = var.owner_contact.phone_number
    address_line_1              = var.owner_contact.address_line_1
    city                        = var.owner_contact.city
    zip                         = var.owner_contact.zip
    country                     = "DE"
    vat_identification_code     = ""
    company_identification_code = ""
  }
}

resource "scaleway_container_namespace" "registry" {
  name        = "jwkserve"
  description = "jwkserve.com Containers"
  project_id  = local.project_id
}

resource "scaleway_container" "container" {
  name           = "jwkserve"
  namespace_id   = scaleway_container_namespace.registry.id
  registry_image = "${scaleway_container_namespace.registry.registry_endpoint}/jwkserve:latest"
  port           = 3000
  cpu_limit      = 100
  memory_limit   = 128
  min_scale      = 1
  max_scale      = 3
  timeout        = 10
  http_option    = "redirected"
  privacy = "public"
  deploy  = true
}

resource "scaleway_container_domain" "domain" {
  container_id = scaleway_container.container.id
  hostname     = "jwkserve.com"
}

resource "scaleway_domain_record" "dns" {
  dns_zone = "jwkserve.com"
  project_id = local.project_id
  type     = "ALIAS"
  data     = "${scaleway_container.container.domain_name}."
  ttl      = 60
}

output "container_id" {
  description = "Container ID"
  value       = element(split("/", scaleway_container.container.id), 1)
}

output "container_hostname" {
  description = "Container hostname"
  value       = scaleway_container.container.domain_name
}

output "container_registry" {
  value       = scaleway_container_namespace.registry.registry_endpoint
  description = "Container Registry Endpoint"
}
