zip:
	zip -9 nessus_lambda.zip nessus.py cloudwatch.py

test:
	export AWS_ACCESS_KEY_ID=AKIA00AA00AAAA0A0AAA
	export AWS_SECRET_ACCESS_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAA
	export AWS_DEFAULT_REGION=eu-west-2
	pipenv run pytest
