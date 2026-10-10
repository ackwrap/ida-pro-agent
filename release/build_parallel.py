#!/usr/bin/env python3
"""Select CMake build concurrency from the CPUs available to this process."""

import argparse
import os


def available_cpu_count():
    process_cpu_count = getattr(os, "process_cpu_count", None)
    if process_cpu_count is not None:
        count = process_cpu_count()
        if count:
            return count
    if hasattr(os, "sched_getaffinity"):
        try:
            return max(1, len(os.sched_getaffinity(0)))
        except OSError:
            pass
    return os.cpu_count() or 1


def positive_jobs(value):
    try:
        count = int(value)
    except (ValueError, TypeError) as error:
        raise argparse.ArgumentTypeError("jobs must be a positive integer") from error
    if count < 1:
        raise argparse.ArgumentTypeError("jobs must be a positive integer")
    return count


def select_build_jobs(requested=None):
    cores = available_cpu_count()
    configured = os.environ.get("CMAKE_BUILD_PARALLEL_LEVEL")
    if requested is not None:
        jobs, source = positive_jobs(requested), "--jobs"
    elif configured:
        jobs, source = positive_jobs(configured), "CMAKE_BUILD_PARALLEL_LEVEL"
    else:
        jobs, source = cores, "automatic"
    print(f"Build parallelism: {cores} available logical CPUs, {jobs} jobs ({source})", flush=True)
    return jobs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=positive_jobs, help="override automatic CPU detection")
    parser.add_argument("--github-env", action="store_true",
                        help="set CMAKE_BUILD_PARALLEL_LEVEL for subsequent Actions steps")
    args = parser.parse_args()
    if args.github_env and not os.environ.get("GITHUB_ENV"):
        parser.error("--github-env requires GITHUB_ENV")
    try:
        jobs = select_build_jobs(args.jobs)
    except argparse.ArgumentTypeError as error:
        parser.error(str(error))
    if args.github_env:
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
            output.write(f"CMAKE_BUILD_PARALLEL_LEVEL={jobs}\n")


if __name__ == "__main__":
    main()
