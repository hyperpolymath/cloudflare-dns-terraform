; SPDX-License-Identifier: MPL-2.0
;; guix.scm — GNU Guix package definition for cloudflare-dns-terraform
;; Usage: guix shell -f guix.scm

(use-modules (guix packages)
             (guix build-system gnu)
             (guix licenses))

(package
  (name "cloudflare-dns-terraform")
  (version "0.1.0")
  (source #f)
  (build-system gnu-build-system)
  (synopsis "cloudflare-dns-terraform")
  (description "cloudflare-dns-terraform — part of the hyperpolymath ecosystem.")
  (home-page "https://github.com/hyperpolymath/cloudflare-dns-terraform")
  (license ((@@ (guix licenses) license) "MPL-2.0"
             "https://github.com/hyperpolymath/palimpsest-license")))
