# BitSight API Quick Reference Guide

This document provides a concise overview of the key details, endpoints, authentication, response formats, and rate limits for integrating with the BitSight Security Ratings API.

---

## 1. Base URL & Common Prefixes

* **Base URL:** `https://api.bitsighttech.com`
* **API Version Resource Prefix:** `https://api.bitsighttech.com/ratings/v1`

---

## 2. Company Lookup by Domain

* **Endpoint Path:** `GET /ratings/v1/companies/search`
* **Query Parameter:** `domain` (e.g., `GET /ratings/v1/companies/search?domain=example.com`)
* **Is lookup required?** **Yes.** Ratings cannot be fetched directly by domain alone on primary company rating endpoints. You must first query `/ratings/v1/companies/search?domain=...` to obtain the company's unique identifier (`guid` / `entity_guid`).

---

## 3. Fetch Company Rating

* **Endpoint Path:** `GET /ratings/v1/companies/{company_guid}`
* **Required Parameters:** 
  * `{company_guid}` *(Path parameter)* — The unique company identifier returned from the domain lookup step.
* **Alternative Endpoint (Portfolio Ratings List):** `GET /ratings/v1/current-ratings` (fetches summary ratings across all monitored portfolio companies).

---

## 4. Auth Scheme & Request Headers

* **Auth Scheme:** **HTTP Basic Authentication**
* **Authorization Header Format:**
  ```http
  Authorization: Basic <base64(api_token:)>
  ```
  *(Pass your BitSight API token as the username with an empty password, e.g., `curl -u api_token:`).*
* **Content/Accept Headers:**
  * `Accept: application/json`
  * `X-Bitsight-Accept: application/json` *(Supported alternative header for systems with restricted standard `Accept` header handling, e.g., RSA Archer).*

---

## 5. Test Data / Fixtures (Sanitized Response Bodies)

### A. Domain Search Lookup (`GET /ratings/v1/companies/search?domain=example.com`)
```json
{
  "count": 1,
  "next": null,
  "previous": null,
  "results": [
    {
      "guid": "123e4567-e89b-12d3-a456-426614174000",
      "name": "Example Corp",
      "primary_domain": "example.com",
      "industry": "Technology",
      "industry_slug": "technology",
      "description": "Example organization description.",
      "website": "https://www.example.com",
      "is_bundled": false,
      "is_primary": true,
      "is_service_provider": false,
      "has_company_tree": false,
      "search_history_count": 12,
      "customer_monitoring_count": 5,
      "confidence": "High",
      "in_portfolio": true
    }
  ]
}
```

### B. Fetch Rating Details (`GET /ratings/v1/companies/{company_guid}`)
```json
{
  "guid": "123e4567-e89b-12d3-a456-426614174000",
  "name": "Example Corp",
  "shortname": "Example",
  "primary_domain": "example.com",
  "homepage": "https://www.example.com",
  "industry": "Technology",
  "industry_slug": "technology",
  "type": "standard",
  "ratings": [
    {
      "rating_date": "2024-01-01",
      "rating": 750,
      "range": "advanced",
      "rating_color": "#008000"
    }
  ],
  "rating_details": {
    "patching_cadence": {
      "name": "Patching Cadence",
      "grade": "A",
      "category": "Diligence"
    }
  }
}
```

---

## 6. Rate Limits & Pagination

* **Pagination:**
  * **Envelope Structure:** Paginated endpoints return top-level metadata including `count` (total records), `next` (URL to the next page), and `previous` (URL to the prior page).
  * **Query Parameters:**
    * `limit`: Sets maximum returned items per request (default is typically `100`).
    * `offset`: Sets starting record index (e.g., `0` for the first page).
* **Rate Limits:**
  * BitSight enforces standard REST rate limits and throttles excessive requests (returning `HTTP 429 Too Many Requests`).
  * Heavy search parameters (such as `expand=details` on search queries) automatically cap total returned records to `10` per response page.
