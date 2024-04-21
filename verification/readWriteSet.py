from argparse import ArgumentParser
import os


def parseArguments():
  parser = ArgumentParser()
  parser.add_argument("-fd", "--first-directory", dest="first",
                      help="Absolute path to first directory of klee output", required=True)
  
  parser.add_argument("-sd", "--second-directory", dest="second",
                      help="Absolute path to second directory of klee output", required=True)

  return parser.parse_args()


def readInFiles(path):
  result = []
  with open(path, 'r') as fp:
    lines = fp.readlines()
  
  for line in lines:
    vars = line.split(', ')
    temp = []
    for var in vars:
      if '}' in var:
        var = var.split('}')[0]
      if '{' in var:
        var = var.split('{')[1]

      var = var.strip()

      if (var != ""):
        temp.append(var)
      
    result.append(temp)
  return result


def determineOverlap(set1, set2):
  return set(set1) & set(set2)


def readWriteSetAnalysis(program1Sets, program2Sets):
  readSet1 = program1Sets[0]
  readSet2 = program2Sets[0]
  writeSet1 = program1Sets[1]
  writeSet2 = program2Sets[1]

  foundOverlap = False
  r1w2 = determineOverlap(readSet1, writeSet2)
  print(f"readset of 1 {readSet1}, writeset of 2 {writeSet2}")
  if r1w2:
    foundOverlap = True
    print("Overlap in read set of first program and write set of second program")
    print(f"These elements overlap: {r1w2}")

  r2w1 = determineOverlap(readSet2, writeSet1)
  if r2w1:
    foundOverlap = True
    print("Overlap in read set of second program and write set of first program")
    print(f"These elements overlap: {r2w1}")
  
  w1w2 = determineOverlap(writeSet1, writeSet2)
  if w1w2:
    foundOverlap = True
    print("Overlap in write set of first program and write set of second program")
    print(f"These elements overlap: {w1w2}")
  
  if not foundOverlap:
    print("No overlap was found in the read and write sets of both programs")


if __name__ == "__main__":
  args = parseArguments()
  path1 = os.path.join(args.first, 'verification')
  path2 = os.path.join(args.second, 'verification')

  program1Sets = readInFiles(path1)
  program2Sets = readInFiles(path2)

  print(f"Read/Write set analysis on {path1} and {path2}")
  readWriteSetAnalysis(program1Sets, program2Sets)