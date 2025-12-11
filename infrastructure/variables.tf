variable "owner_contact" {
  description = "Domain owner contact information"
  type = object({
    email                       = string
    phone_number                = string
    address_line_1              = string
    city                        = string
    zip                         = string
  })
}
