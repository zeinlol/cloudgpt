import argparse


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Retrieve all customer managed policies and check the default policy version for vulnerabilities')
    parser.add_argument('-k', '--key', type=str, required=True, help='OpenAI API key')
    parser.add_argument('-p', '--profile', type=str, default=None,
                        help='AWS profile name to use (default: default)')
    parser.add_argument('-r', '--redact', action='store_true', default=True,
                        help='Redact sensitive information in the policy document (default: True)')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help="Output file name. If not set results will be saved in 'cache' folder")
    parser.add_argument('-j', '--json', action='store_true', default=False,
                        help='Save results as JSON instead of CSV (default: False)')
    parser.add_argument('-ak', '--amazon-key', type=str, default=None,
                        help="The AWS access key id")
    parser.add_argument('-as', '--secret-key', type=str, default=None,
                        help="The AWS secret access key.")
    parser.add_argument('-at', '--token', type=str, default=None,
                        help="The AWS session token to use.")
    parser.add_argument('-ar', '--region', type=str, default=None,
                        help="Region to use.")

    return parser.parse_args()


cli_arguments = parse_arguments()
