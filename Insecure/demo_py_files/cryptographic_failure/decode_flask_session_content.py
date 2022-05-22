import base64

# add === for padding to decode flask session
# sessionExample = "eyJ1c2VyIjoiNjU3YTllM2Y0NGU2NGU3ODkwZjM3OGVkNGVhNmVmYzAifQ.YooUlA.xr_w4g9TAIn9EXpsvxdFx3mbtNE"
sessionInp = input("Enter session cookie value: ")
print(base64.urlsafe_b64decode(sessionInp.split(".")[0] + "==="))