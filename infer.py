from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import cross_validate, KFold, cross_val_predict, train_test_split
from sklearn.metrics import make_scorer, accuracy_score, classification_report
import numpy as np

CCAS = ["cubic", "reno", "bbr", "bic", "highspeed", "htcp", "illinois", "scalable", "vegas", "veno", "westwood", "yeah"]
CCA_ID_MAPPING = dict([(CCAS[i], i) for i in range(len(CCAS))])
RUN_ID = "1705029330"

def parse_results():
    run_dir = f"traces/run-{RUN_ID}/"
    X_MINE = []
    X_ORIG = []
    X_CWND = []
    Y = []

    for cca in CCAS:
        with open(run_dir + cca + "/vectors-mine.txt", 'r') as f:
            lines = f.readlines()
            my_vecs = list(map(lambda s: s.strip().replace("(", "").replace(")", "").split(","), map(lambda s: s.strip(), lines)))

        with open(run_dir + cca + "/vectors-orig.txt", 'r') as f:
            lines = f.readlines()
            orig_vecs = list(map(lambda s: s.strip().replace("[", "").replace("]","").split(","), lines))

        with open(run_dir + cca + "/vectors-cwnds.txt", 'r') as f:
            lines = f.readlines()
            cwnd_vecs = list(map(lambda s: s.strip().replace("[", "").replace("]","").split(","), lines))

        assert(len(my_vecs) == len(orig_vecs))
        X_MINE.extend(my_vecs)
        X_ORIG.extend(orig_vecs)
        X_CWND.extend(cwnd_vecs)

        Y.extend([CCA_ID_MAPPING[cca] for _ in range(len(my_vecs))])
    
    cwnd_max_len = max([len(c) for c in X_CWND]) 
    X_CWND = [c + [0 for _ in range(cwnd_max_len - len(c))] for c in X_CWND]
    return (X_MINE, X_ORIG, X_CWND, Y)
    

if __name__ == "__main__":
    (X_MINE, X_ORIG, X_CWND, Y) = parse_results()

    X_MINE = list(map(lambda x: list(map(int, x)), X_MINE))
    X_ORIG = list(map(lambda x: list(map(float, x)), X_ORIG))
    X_CWND = list(map(lambda x: list(map(int, x)), X_CWND))

    # print(X_ORIG)
    
    tree = DecisionTreeClassifier(criterion="entropy")
    # tree = DecisionTreeClassifier()

    scoring = {'acc0': make_scorer(accuracy_score, labels = [0]), 
       'acc1': make_scorer(accuracy_score, labels = [1]),
       'acc2': make_scorer(accuracy_score, labels = [2])}

    cv_mine = cross_validate(tree, X_MINE, y=Y, cv=10)
    cv_orig = cross_validate(tree, X_ORIG, y=Y, cv=10)
    cv_cwnds = cross_validate(tree, X_CWND, y=Y, cv=10)

    print(cv_cwnds)
    print(cv_mine)
    print(cv_orig)

    ####
    # KFold cross validation
    tree = DecisionTreeClassifier(criterion="entropy")
    X_train, X_test, y_train, y_test = train_test_split(X_CWND, Y, random_state=1)
    tree.fit(X_train, y_train)
    
    y_pred = tree.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=CCAS))




