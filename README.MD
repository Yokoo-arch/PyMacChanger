# PyMacChanger

![GitHub stars](https://img.shields.io/github/stars/Yokoo-arch/PyMacChanger?style=social)
![GitHub forks](https://img.shields.io/github/forks/Yokoo-arch/PyMacChanger?style=social)
![GitHub issues](https://img.shields.io/github/issues/Yokoo-arch/PyMacChanger)
![GitHub license](https://img.shields.io/github/license/Yokoo-arch/PyMacChanger)

PyMacChanger is a Python script for changing the MAC address of a network interface on macOS. It provides several modes for changing the MAC address, including randomization and manual specification.

## Features

- Change the MAC address of a network interface.
- Randomize the MAC address.
- Specify a manual MAC address.
- Revert to the original MAC address.
- Copy the generated MAC address to the clipboard.

## Prerequisites

- macOS (tested on macOS Ventura: Version 13.5)
- Python 3.x

## Installation

1. Clone the repository:

   ```shell
   git clone https://github.com/Yokoo-arch/PyMacChanger.git
   cd PyMacChanger

2. Install the required Python packages:
    ```shell
    pip install -r requirements.txt

## Usage
Run the script with the desired options:

```shell
python main.py -i <interface> -r
```
```
`-i`, `--interface`: Name of the interface (required).
`-r`, `--random`: Change the MAC address to a random one.
`-m`, `--manual`: Change the MAC address to a specified one.
`-ma`, `--mac-address`: MAC address used for manual mode.
`-p`, `--permanent-mac-address`: Revert to the original MAC address.
`-g`, `--generate-random-mac`: Generate and copy a random MAC address to the clipboard.
```
## Examples
Change the MAC address of Wi-Fi (en0) to a random one:
```shell
python main.py -i en0 -r
````

Change the MAC address of Ethernet (en1) to a manual one:
```shell
python main.py -i en1 -m -ma 12:34:56:78:90:ab
```

Revert the MAC address of Wi-Fi (en0) to the permanent one:
```shell
python main.py -i en0 -p
```

## Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## License
This project is licensed under the MIT License - see the **LICENSE** file for details.