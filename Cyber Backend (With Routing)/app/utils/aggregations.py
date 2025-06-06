latest_vuln_stages = [
    {
        "$sort": {
            "Plugin Modification Date": -1,
            "IP Address": 1,
            "Plugin Name": 1,
            "Port": 1
        }
    },
    {
        "$group": {
            "_id": {
                "ip": "$IP Address",
                "plugin": "$Plugin Name",
                "port": "$Port"
            },
            "doc": {"$first": "$$ROOT"}
        }
    },
    {"$replaceRoot": {"newRoot": "$doc"}}
]