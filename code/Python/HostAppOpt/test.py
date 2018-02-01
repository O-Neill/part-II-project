import PBStore


store = PBStore.Store('store.xml')
a = 2000
b = 3000
store.addRecord(4, a.to_bytes((a.bit_length() // 8) + 1, byteorder='big'))
store.addRecord(5, b.to_bytes((b.bit_length() // 8) + 1, byteorder='big'))

print(store.getSecret(4))
