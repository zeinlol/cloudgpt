class Policy:
    def __init__(self,
                 account=None,
                 arn=None,
                 name=None,
                 version=None,
                 policy=None,
                 original_document=None,
                 redacted_document=None,
                 ai_response=None
                 ):
        self.account = account
        self.arn = arn
        self.name = name
        self.version = version
        self.policy = policy
        self.original_document: str | None = original_document
        self.redacted_document = redacted_document
        self.ai_response: str | None = ai_response
        self.account_mapping: dict = {}

    def __repr__(self) -> str:
        return 'Policy()'

    def __str__(self) -> str:
        return f'<Policy name:{self.name}>'

    def map_accounts(self, old, new) -> None:
        self.account_mapping[old] = new

    def retrieve_mappings(self) -> str:
        maps = [f'{k}->{v}' for k, v in self.account_mapping.items()]
        return ', '.join(maps)

    def is_changed(self) -> bool:
        return self.original_document != self.redacted_document

    def is_vulnerable(self) -> str:

        if 'Yes,' in self.ai_response:
            return 'VULNERABLE'
        elif 'No,' in self.ai_response:
            return 'NOT VULNERABLE'
        return 'CHECK CSV'
