from app.gmail_labels import label_name_for_verdict, ensure_label, label_message_for_verdict


def test_benign_verdict_gets_no_label():
    assert label_name_for_verdict("benign_or_low_risk") is None


def test_each_non_benign_verdict_maps_to_a_distinct_label():
    names = {
        label_name_for_verdict("phishing"),
        label_name_for_verdict("suspicious"),
        label_name_for_verdict("needs_review"),
    }
    assert None not in names
    assert len(names) == 3  # all distinct -- mirrors the dashboard's own verdict badges


class FakeLabelsResource:
    def __init__(self, existing=None):
        self.existing = existing or []
        self.created = []

    def list(self, userId):
        return self

    def create(self, userId, body):
        self.created.append(body)
        return self

    def execute(self):
        if self.created:
            return {"id": f"created-{len(self.created)}", "name": self.created[-1]["name"]}
        return {"labels": self.existing}


class FakeMessagesResource:
    def __init__(self):
        self.modified = []

    def modify(self, userId, id, body):
        self.modified.append((id, body))
        return self

    def execute(self):
        return {}


class FakeService:
    def __init__(self, existing_labels=None):
        self._labels = FakeLabelsResource(existing_labels)
        self._messages = FakeMessagesResource()

    def users(self):
        return self

    def labels(self):
        return self._labels

    def messages(self):
        return self._messages


def test_ensure_label_creates_when_missing():
    service = FakeService(existing_labels=[])
    from app import gmail_labels
    gmail_labels._label_id_cache.clear()

    label_id = ensure_label(service, "PhishScope/Phishing")
    assert label_id == "created-1"
    assert service._labels.created[0]["name"] == "PhishScope/Phishing"


def test_ensure_label_reuses_existing_without_creating():
    service = FakeService(existing_labels=[{"id": "abc123", "name": "PhishScope/Suspicious"}])
    from app import gmail_labels
    gmail_labels._label_id_cache.clear()

    label_id = ensure_label(service, "PhishScope/Suspicious")
    assert label_id == "abc123"
    assert service._labels.created == []


def test_label_message_for_verdict_applies_and_returns_name():
    service = FakeService(existing_labels=[{"id": "xyz", "name": "PhishScope/Phishing"}])
    from app import gmail_labels
    gmail_labels._label_id_cache.clear()

    result = label_message_for_verdict(service, "msg-1", "phishing")
    assert result == "PhishScope/Phishing"
    assert service._messages.modified == [("msg-1", {"addLabelIds": ["xyz"]})]


def test_label_message_for_verdict_skips_benign():
    service = FakeService()
    result = label_message_for_verdict(service, "msg-1", "benign_or_low_risk")
    assert result is None
    assert service._messages.modified == []
