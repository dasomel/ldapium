#!/usr/bin/env python3
"""Plot LDAP load latency percentiles and large-load completion from profiles."""

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib import font_manager


def read_profile(path: Path, expected_status: str) -> dict:
    profile = json.loads(path.read_text(encoding="utf-8"))
    if profile.get("status") != expected_status:
        raise ValueError(
            f"{path}: expected status {expected_status!r}, got {profile.get('status')!r}"
        )
    return profile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--five-m",
        type=Path,
        default=Path(".local/ldap-load-results/large-5m/bench-profile-5000000-20261001T142806Z.json"),
    )
    parser.add_argument(
        "--ten-m",
        type=Path,
        default=Path(".local/ldap-load-results/large-10m/bench-profile-10000000-20261001T133046Z.json"),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("docs/testing/ldap-large-load-results-ko.png"),
    )
    args = parser.parse_args()

    five_m = read_profile(args.five_m, "ok")
    ten_m = read_profile(args.ten_m, "timed-out")
    search = five_m["search"]
    writes = five_m["writeLatency"]
    percentile_keys = ("latencyMsP50", "latencyMsP95", "latencyMsP99")
    percentile_labels = ("p50", "p95", "p99")
    colors = ("#73A9D8", "#2468A8", "#153B64")

    plt.style.use("seaborn-v0_8-whitegrid")
    font_path = font_manager.findfont("AppleGothic")
    plt.rcParams["font.family"] = font_manager.FontProperties(fname=font_path).get_name()
    plt.rcParams["axes.unicode_minus"] = False

    fig, (latency_ax, completion_ax) = plt.subplots(
        1, 2, figsize=(13, 5.6), gridspec_kw={"width_ratios": (1.45, 1)}
    )
    fig.suptitle("LDAP 대용량 부하 테스트 결과", fontsize=17, fontweight="bold", y=1.02)

    groups = (("검색 (5M 데이터)", search), ("순차 쓰기 (5M 데이터)", writes))
    centers = (0, 1)
    bar_width = 0.19
    for percentile_index, (label, color) in enumerate(zip(percentile_labels, colors)):
        values = [group[1][percentile_keys[percentile_index]] for group in groups]
        offsets = [center + (percentile_index - 1) * bar_width for center in centers]
        bars = latency_ax.bar(offsets, values, width=bar_width, label=label, color=color)
        for bar, value in zip(bars, values):
            latency_ax.annotate(
                f"{value:.0f}",
                (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                xytext=(0, 4),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=8,
            )
    latency_ax.set_title("응답 지연시간 백분위", fontsize=13, fontweight="bold")
    latency_ax.set_ylabel("지연시간 (ms)")
    latency_ax.set_xticks(centers, [group[0] for group in groups])
    latency_ax.set_ylim(0, max(search["latencyMsP99"], writes["latencyMsP99"]) * 1.2)
    latency_ax.legend(title="백분위", frameon=False, ncols=3, loc="upper left")
    latency_ax.spines["top"].set_visible(False)
    latency_ax.spines["right"].set_visible(False)

    progress_rows = (five_m, ten_m)
    labels = ("5M 요청 · 완료", "10M 요청 · 55분 제한")
    bar_colors = ("#218739", "#D28A00")
    completion_ax.set_title("요청 대비 적재 완료율", fontsize=13, fontweight="bold")
    for y, (profile, label, color) in enumerate(zip(progress_rows, labels, bar_colors)):
        requested = profile["requestedEntries"]
        loaded = profile["loadedCount"]
        ratio = loaded / requested
        completion_ax.barh(y, ratio * 100, color=color, height=0.48)
        completion_ax.text(
            104,
            y,
            f"{loaded / 1_000_000:.2f}M / {requested / 1_000_000:.0f}M  ({ratio:.1%})",
            va="center",
            ha="left",
            fontsize=9,
        )
        completion_ax.text(0.5, y, label, color="white", va="center", ha="left", fontsize=9)
    completion_ax.set_yticks([])
    completion_ax.set_xlim(0, 132)
    completion_ax.set_xlabel("목표 적재량 대비 완료율 (%)")
    completion_ax.set_xticks((0, 25, 50, 75, 100), ("0", "25", "50", "75", "100%"))
    completion_ax.invert_yaxis()
    completion_ax.spines["top"].set_visible(False)
    completion_ax.spines["right"].set_visible(False)
    completion_ax.spines["left"].set_visible(False)

    fig.text(
        0.5,
        0.005,
        "5M 검색은 50 작업자 × 200회 · 10M 프로파일은 제한 시 검색·쓰기 생략 · 검색 시간에 docker exec 비용 포함",
        ha="center",
        fontsize=9,
        color="#444444",
    )
    fig.tight_layout(rect=(0, 0.045, 1, 0.97))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.out, dpi=180, bbox_inches="tight")
    print(args.out)


if __name__ == "__main__":
    main()
