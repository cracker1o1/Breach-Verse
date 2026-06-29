import base64

value = "VjIweFUyTlhSWGxYYlhSb1lsaG9lVmR0"

for level in range(1, 20):
    try:
        padded = value + "=" * (-len(value) % 4)

        decoded = base64.b64decode(padded)

        print(f"\nLevel {level}")
        print("Input :", value)
        print("Output:", decoded)

        value = decoded.decode("utf-8")

    except Exception as e:
        print(f"\nStopped at level {level}")
        print(e)
        break
