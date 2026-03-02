;; SPDX-License-Identifier: PMPL-1.0-or-later
(ecosystem
  (metadata
    (version "0.1.0")
    (last-updated "2026-03-02"))
  (project
    (name "cloudflare-dns-terraform")
    (purpose "Infrastructure-as-code for managing DNS records across all hyperpolymath domains via Terraform and Cloudflare")
    (role dns-infrastructure))
  (related-projects
    (project "consent-aware-http" (relationship sibling-standard) (description "Consent-aware HTTP protocol implemented as Cloudflare Worker"))
    (project "rescript-dom-mounter" (relationship potential-consumer) (description "SafeDOM uses domains managed here"))
    (project "casket-ssg" (relationship potential-consumer) (description "Static sites deployed to domains managed here"))))
