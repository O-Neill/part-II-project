import base64


testarr = [23, 5, 23, 66, 32, 126, 81, 181]
b = bytes(testarr)

print(b)

s = b.decode(errors='surrogateescape')
print(type(s))

b2 = s.encode(errors='surrogateescape')
print(type(b2))
print(b2)
print(i for i in b2)
