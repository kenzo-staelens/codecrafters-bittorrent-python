import logging

loglevel = logging.DEBUG
req_handler = logging.StreamHandler(open("saved/logs/incoming-requests.log","a"))
req_handler.setLevel(loglevel)
formatter = logging.Formatter('%(levelname)s - [%(asctime)s] {%(module)s:%(lineno)d} %(message)s','%d-%m-%y %H:%M:%S')
req_handler.setFormatter(formatter)
stdout_handler = logging.StreamHandler()
stdout_handler.setFormatter(formatter)

def register_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(loglevel)
    logger.addHandler(req_handler)
    logger.addHandler(stdout_handler)
    return logger