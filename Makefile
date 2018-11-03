package:
	python setup.py sdist bdist_wheel

test_upload:
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*

upload:
	python setup.py upload
