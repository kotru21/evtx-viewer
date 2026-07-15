"""Константы предметной области: схема событий, наборы EID, приоритеты полей."""

NS = 'http://schemas.microsoft.com/win/2004/08/events/event'

# EventID, помечаемые как security-relevant (подсветка + метка в сводке)
HOT_EID = {
    '1102', '104', '4624', '4625', '4634', '4648', '4672', '4720', '4732', '4728',
    '7045', '1149', '21', '22', '1', '3', '10', '11', '13',
}

# Поля для однострочной сводки события, в порядке приоритета показа
INTERESTING_FIELDS = (
    'Image', 'TargetImage', 'SourceImage', 'CommandLine', 'User',
    'SubjectUserName', 'TargetUserName', 'ParentImage',
    'DestinationIp', 'DestinationPort', 'SourceIp', 'SourcePort', 'Initiated',
    'TargetFilename', 'TargetObject', 'IpAddress', 'LogonType', 'ServiceName',
)
