#python file to create logic for checking passwords
def checkPass(password):
  score = 0  #increment score with each passed point.
  if (password >= 12):
    #additional password requirements to be added according to safe practice
    #add to error message / improvements if missed
