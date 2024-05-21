import re
def is_valid_password(password):
    reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{12,20}$"
    reg_com = re.compile(reg)
    return re.search(reg_com,password) is not None
