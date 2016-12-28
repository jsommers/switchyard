from code import InteractiveConsole
import sys

console = InteractiveConsole()
for line in sys.stdin:
    print(">>> {}".format(line.strip()))
    console.push(line.strip())

