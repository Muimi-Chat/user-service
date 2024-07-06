import re
def is_valid_password(password):
    reg = "^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d_\-\!@#$%^&*]{8,72}$"
    reg_com = re.compile(reg)
    return re.search(reg_com,password) is not None
