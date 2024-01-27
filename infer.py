from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import cross_validate, KFold, cross_val_predict, train_test_split
from sklearn.metrics import make_scorer, accuracy_score, classification_report
import numpy as np

from pyts.metrics import dtw

import matplotlib.pyplot as plt
from matplotlib import style

plt.rcParams.update(plt.rcParamsDefault)
plt.style.use(['seaborn-v0_8-paper','seaborn-v0_8-colorblind'])
plt.rc('font', size=20)
plt.rc('axes', titlesize=20, titleweight='bold', labelsize=20)
plt.rc('xtick', labelsize=20)
plt.rc('ytick', labelsize=20)
plt.rc('legend', fontsize=20)
plt.rc('figure', titlesize=20)
plt.rc('lines', linewidth=3)
plt.rc('axes.spines', right=False, top=False)

# testing_cca, ig-azure, ig-aws
# bbr, 5, 728712871821

CCAS = ["cubic", "reno", "bbr", "bic", "highspeed", "htcp", "illinois", "scalable", "vegas", "veno", "westwood", "yeah"]
# CCAS = ["cubic", "reno", "yeah"]
# CCAS = ["cubic", "reno", "bbr"]
CCA_ID_MAPPING = dict([(CCAS[i], i) for i in range(len(CCAS))])

# RUN_ID = "pruned"

# aws run = 17054...

# RUN_ID = "1706073704"

RUN_ID = "pruned"

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
    X_CWND_PADDED = [c + [0 for _ in range(cwnd_max_len - len(c))] for c in X_CWND]
    return (X_MINE, X_ORIG, X_CWND_PADDED, X_CWND, Y)


def get_nn_dtw(X_train, Y_train, x):
    assert(len(X_train) == len(Y_train))

    closest_dist = float("inf")
    i_closest = 0
    for i in range(len(X_train)):
        min_len = min(len(X_train[i]), len(x))
        x_train = X_train[i][:min_len]
        x_sample = x[:min_len]

        dist = dtw(x_train, x_sample, dist='square', method='classic')

        if dist < closest_dist:
            closest_dist = dist
            i_closest = i
    
    print(f"Closest for sample is {i_closest} with class {Y_train[i_closest]} dist {closest_dist}")
    print(X_train[i_closest])
    return (Y_train[i_closest], i_closest)


if __name__ == "__main__":
    (X_MINE, X_ORIG, X_CWND, X_CWND_UNPAD, Y) = parse_results()

    X_MINE = list(map(lambda x: list(map(int, x)), X_MINE))
    X_ORIG = list(map(lambda x: list(map(float, x)), X_ORIG))
    X_CWND = list(map(lambda x: list(map(int, x)), X_CWND))
    X_CWND_UNPAD = list(map(lambda x: list(map(int, x)), X_CWND_UNPAD))

    # print(X_ORIG)
    
    ######
    # 10-fold cv for decision tree on 3 vector types
    tree = DecisionTreeClassifier(criterion="entropy")
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
    # Do a single fold and pretty-print results
    tree = DecisionTreeClassifier(criterion="entropy")
    X_train, X_test, y_train, y_test = train_test_split(X_CWND, Y, random_state=1)
    tree.fit(X_train, y_train)
    
    y_pred = tree.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=CCAS))


    # ########
    # DTW
    # X_train, X_test, y_train, y_test = train_test_split(X_CWND_UNPAD, Y, random_state=1)

    # y_pred_and_closests = [get_nn_dtw(X_train, y_train, x) for x in X_test]
    # y_pred = [x[0] for x in y_pred_and_closests]
    # closests = [x[1] for x in y_pred_and_closests]
    # print(classification_report(y_test, y_pred, target_names=CCAS))
    # print(len(X_train), len(X_test))

    #########
    # DTW mismatch plots
    # for i in range(len(X_test)):
    #     if y_pred[i] != y_test[i]:
    #         x = [j for j in range(len(X_test[i]))]
    #         plt.plot(x, X_test[i])
    #         x = [j for j in range(len(X_train[i]))]
    #         plt.plot(x, X_train[i])
    #         print("Actual:", CCAS[y_test[i]], "Closest match:", CCAS[y_pred[i]])
    #         plt.show()

    # ########
    # General CCA plots
    # ccas_to_plot = ["highspeed", "htcp", "veno"]
    # num_plotted = [0 for _ in CCAS]
    # cca_colors = ["blue", "orange", "black", "green"]

    # # for cca_to_plot in range(len(CCAS)):
    # #     num_plotted = 0
    # for i in range(len(X_CWND_UNPAD)):
    #     if CCAS[Y[i]] in ccas_to_plot and num_plotted[Y[i]] < 2:
    #         x = [j for j in range(len(X_CWND_UNPAD[i]))]
    #         color = cca_colors[ccas_to_plot.index(CCAS[Y[i]])]

    #         if num_plotted[Y[i]] == 0:
    #             plt.plot(x, X_CWND_UNPAD[i], color=color, label = CCAS[Y[i]])
    #         else:
    #             plt.plot(x, X_CWND_UNPAD[i], color=color)
    #         num_plotted[Y[i]] += 1

    # # print(num_plotted)
    # # print("Showing graph for", CCAS[cca_to_plot])
    # plt.xlabel("Turn")
    # plt.ylabel("CWND (#packets)")
    # plt.legend()
    # plt.title("CCA Comparison, 2 Sample Traces")
    # plt.show()


    # Manual bar graphs for accuracy blehhh
    recall = [0.79, 0.6, 0.8, 0.36, 0.23, 0.27, 0.00, 0.40, 1.00, 0.24, 0.13, 0.78]
    plt.bar(CCAS, recall)
    plt.xlabel("CCA")
    plt.ylabel("Recall")
    plt.title("Inspector Gadget Classification (AWS)")
    plt.show()