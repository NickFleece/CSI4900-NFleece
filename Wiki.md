Datasets being used:
- Malicious data being generated using: https://github.com/PaulSec/DET
- Benign data: https://www.unb.ca/cic/datasets/dos-dataset.html (may be noted that this only contains about 60,000 DNS queries, the DDoS has much more)

Features:
- Specifically for packets:
  - Length of the concatenated string
  - Entropy of the concatenated string
  - Ratios of:
    - Upper-case and lower-case letters vs the rest of the string
    - Alphabetic string vs the rest of the string
    - Number of digits in the subdomain
    - Length of longest meaningful word vs subdomain length
  - Number of the unique subdomains in the query
- Relating to traffic:
  - Query volume per domain
  - Query frequency per domain
