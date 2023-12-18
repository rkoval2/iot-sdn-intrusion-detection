import pandas as pd

from preprocessing import preprocess

headers = open('data/headers', 'r').read().split('\n')
headers.append('label')
df = pd.read_csv("data/kddcup.data_10_percent.csv", names=headers, index_col=None)
df, labels = preprocess(df, "cluster")

# df.loc[[0]].to_csv("data/input2.csv", index=False)
