from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import cross_validate
import numpy as np

CCAS = ["cubic", "reno", "bbr", "bic", "highspeed", "htcp", "illinois", "scalable", "vegas", "veno", "westwood", "yeah"]
CCA_ID_MAPPING = dict([(CCAS[i], i) for i in range(len(CCAS))])
RUN_ID = "1702858527"

def parse_results():
    run_dir = f"traces/run-{RUN_ID}/"
    X_MINE = []
    X_ORIG = []
    Y = []

    for cca in CCAS:
        with open(run_dir + cca + "/vectors-mine.txt", 'r') as f:
            lines = f.readlines()
            my_vecs = list(map(lambda s: s.strip().replace("(", "").replace(")", "").split(","), map(lambda s: s.strip(), lines)))

        with open(run_dir + cca + "/vectors-orig.txt", 'r') as f:
            lines = f.readlines()
            orig_vecs = list(map(lambda s: s.strip().replace("[", "").replace("]","").split(","), lines))
        
        assert(len(my_vecs) == len(orig_vecs))
        X_MINE.extend(my_vecs)
        X_ORIG.extend(orig_vecs)

        Y.extend([CCA_ID_MAPPING[cca] for _ in range(len(my_vecs))])
    
    return (X_MINE, X_ORIG, Y)
    

if __name__ == "__main__":
    (X_MINE, X_ORIG, Y) = parse_results()
    
    tree = DecisionTreeClassifier(criterion="entropy")

    cv_mine = cross_validate(tree, X_MINE, y=Y, cv=10)
    cv_orig = cross_validate(tree, X_ORIG, y=Y, cv=10)

    print(cv_mine)
    print(cv_orig)




