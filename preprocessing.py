import pandas
import pandas as pd


def preprocess(df: pandas.DataFrame, mode='classification', sample=None):
    pd.set_option('mode.chained_assignment', None)
    df = df.query(
        'label == "back." or label == "land." or label == "neptune." or label == "pod." '
        'or label == "smurf." or label == "teardrop." or label == "normal."', inplace=False)

    df['result'] = df['label'].apply(lambda x: 0 if x == 'normal.' else 1)

    df = df[['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
             'land', 'wrong_fragment', 'urgent', 'count', 'serror_rate', 'rerror_rate', 'same_srv_rate',
             'diff_srv_rate', 'srv_count', 'srv_serror_rate', 'srv_rerror_rate', 'srv_diff_host_rate', 'label',
             'result']]

    df = pd.get_dummies(df, columns=['protocol_type', 'service', 'flag'])

    if sample is not None:
        df = df.sample(n=sample, random_state=1)

    if mode == 'classification':
        from sklearn.preprocessing import LabelEncoder
        le = LabelEncoder()
        df = df.drop('label', axis=1)
        labels_true = le.fit_transform(df['result'])
        df = df.drop('result', axis=1)
        return (df, labels_true)  # X, y
    elif mode == 'cluster':
        labels_true = df['result']
        df = df.drop('label', axis=1)
        df = df.drop('result', axis=1)
        return (df, labels_true)  # X, y
