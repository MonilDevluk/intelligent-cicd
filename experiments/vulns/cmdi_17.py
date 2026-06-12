import subprocess
def convert_image(input_file, output_format):
    result = subprocess.check_output("convert " + input_file + " " + output_format, shell=True)
    return result.decode()
def resize_image(input_file, dimensions):
    result = subprocess.check_output("convert " + input_file + " -resize " + dimensions + " output.jpg", shell=True)
    return result.decode()
def get_image_info(input_file):
    result = subprocess.check_output("identify " + input_file, shell=True)
    return result.decode()
