window.BENCHMARK_DATA = {
  "lastUpdate": 1756385813276,
  "repoUrl": "https://github.com/developeruche/ethrex",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "git@edgl.dev",
            "name": "Edgar",
            "username": "edg-l"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f6dcb766bd3d274a36664a2074228257061e6387",
          "message": "perf(levm): improvements to precompiles (#4168)\n\nMinor improvements:\n\n- In fill_with_zeros, when the size is already target or more avoid\nallocating a vec.\n- Also avoided allocating vecs in other contexts.\n- Improved further the modexp code, making it more predictable to\ncompiler optimizations.\n- Changed some infallible functions from returning a Result to a value\ndirectly.\n\n\nNeed to measure if it improves.\n\n<img width=\"1347\" height=\"260\" alt=\"image\"\nsrc=\"https://github.com/user-attachments/assets/a934cf61-aed9-4f7a-bfc6-861ee8c16ebc\"\n/>",
          "timestamp": "2025-08-28T10:21:53Z",
          "tree_id": "661b8aec00535bb7c6028f520fe84aea0814819a",
          "url": "https://github.com/developeruche/ethrex/commit/f6dcb766bd3d274a36664a2074228257061e6387"
        },
        "date": 1756385811686,
        "tool": "cargo",
        "benches": [
          {
            "name": "Block import/Block import ERC20 transfers",
            "value": 159915886696,
            "range": "± 201241873",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}