.DEFAULT_GOAL := zip
.PHONY = clean

target_dir:
	mkdir -p target

copy_src: target_dir
	cp nessus.py process_scans.py target

# https://github.com/pypa/pipenv/issues/746
add_deps: target_dir
	pipenv lock -r | sed 's/-e //g' | pipenv run pip3 install --upgrade -r /dev/stdin --target target

clean:
	rm -rf target *.egg-info .tox venv *.zip .pytest_cache htmlcov **/__pycache__

zip: add_deps copy_src
	cd target; zip -X -9 ../process_scans.zip -r .
