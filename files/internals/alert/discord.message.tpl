{
	"embeds": [
		{
			"title": "LMD Alert: {{HOSTNAME}}",
			"description": "**{{TOTAL_HITS}}** threat(s) detected | {{SCAN_STARTED}}",
			"color": 557490,
			"fields": [
{{ENTRY_FIELDS}}
				{
					"name": "Summary",
					"value": "{{SUMMARY_TOTAL_HITS}} hits | {{SUMMARY_TOTAL_CLEANED}} cleaned | {{SUMMARY_BY_TYPE}}\n{{SUMMARY_QUARANTINE_STATUS}}",
					"inline": false
				}
			],
			"footer": {
				"text": "LMD {{LMD_VERSION}} | rfxn.com"
			}
		}
	]
}
