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
        self.account: str = account
        self.arn: str = arn
        self.name: str = name
        self.version: str = version
        self.policy: str = policy
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

    @property
    def is_vulnerable(self) -> bool | None:

        if 'Yes,' in self.ai_response:
            return True
        elif 'No,' in self.ai_response:
            return False
        return None

    @property
    def is_vulnerable_text(self) -> str:
        if self.is_vulnerable:
            return 'VULNERABLE'
        elif self.is_vulnerable is False:
            return 'NOT VULNERABLE'
        else:
            return 'CHECK CSV'

    def get_mapping(self):
        return '' if len(self.retrieve_mappings()) == 0 else self.retrieve_mappings()

    def dict(self) -> dict:
        return {
            'account': self.account,
            'name': self.name,
            'arn': self.arn,
            'version': self.version,
            'policy': self.original_document,
            'vulnerable': self.ai_response,
            'mappings': self.get_mapping(),
            'is_vulnerable': self.is_vulnerable,
        }