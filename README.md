# HSTS Header Checker

A Python tool to check HTTP Strict Transport Security (HSTS) headers for multiple websites in parallel. This tool validates HSTS configurations, classifies their security level, and exports detailed results to CSV.

## Features

- ✅ **Parallel checking** - Tests multiple sites simultaneously for faster results
- 📊 **CSV export** - Automatically generates timestamped CSV reports
- 🎯 **Smart classification** - Rates HSTS configurations from Excellent to Missing
- 📈 **Progress bar** - Real-time progress tracking with tqdm
- 🔍 **Detailed analysis** - Parses max-age, includeSubDomains, and preload directives
- ⚡ **Error handling** - Gracefully handles SSL errors, timeouts, and connection issues

## Requirements

- Python 3.7+
- Dependencies listed in `requirements.txt`:
  - requests
  - tqdm

## Installation

1. Clone or download this repository
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

1. Create a text file with domains to check (one per line):

```
example.com
github.com
https://google.com
twitter.com
# Comments are supported
facebook.com
```

2. Run the checker:

```bash
python check_hsts.py domains.txt
```

3. View results in the terminal and check the generated CSV file

## HSTS Classification

The tool classifies HSTS configurations into the following categories:

| Emoji | Classification | Criteria |
|-------|---------------|----------|
| 🔒✅ | **Excellent** | max-age ≥ 1 year + includeSubDomains + preload |
| ✅🛡️ | **Strong** | max-age ≥ 1 year + includeSubDomains |
| ✅ | **Good** | max-age ≥ 1 year |
| ⚠️ | **Weak** | max-age < 1 year |
| ❌ | **Missing** | No HSTS header present |
| 🔓 | **SSL Error** | SSL/TLS connection failed |
| 🔌 | **Connection Error** | Unable to reach the server |
| ⏱️ | **Timeout** | Request timed out (10s limit) |

## Output

### Terminal Output

The tool displays detailed information for each domain:

```
🔍 Checking HSTS headers for 3 address(es)...
================================================================================
Checking HSTS: 100%|████████████████████| 3/3 [00:02<00:00, 1.50site/s]

🔒✅ github.com
   Classification: Excellent
   HSTS Header: max-age=31536000; includeSubDomains; preload
   Max-Age: 31536000 seconds (365 days)
   🛡️  includeSubDomains: enabled
   🔒 preload: enabled
--------------------------------------------------------------------------------
```

### CSV Export

Results are automatically exported to a timestamped CSV file (e.g., `hsts_results_20260123_143022.csv`) with the following columns:

- Address
- Classification
- HSTS Header
- Max-Age (seconds)
- Max-Age (days)
- includeSubDomains
- preload

## Performance

The tool uses parallel processing with up to 10 concurrent workers, making it significantly faster than sequential checking. For example:
- 50 domains: ~5-10 seconds (vs ~50+ seconds sequentially)
- 100 domains: ~10-20 seconds (vs ~100+ seconds sequentially)

## Configuration

You can adjust the number of parallel workers by modifying the `max_workers` value in the code:

```python
max_workers = min(10, len(addresses))  # Default: 10
```

## Error Handling

The tool handles various error scenarios:
- SSL certificate errors
- Network connection issues
- Request timeouts (10 second limit)
- Invalid URLs
- Missing or malformed HSTS headers

## License

This project is open source and available for use and modification.

## Contributing

Feel free to open issues or submit pull requests with improvements.
