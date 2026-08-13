"""
ML model training script

This script trains the URL threat classification model using a labeled dataset.

Dataset preparation:
1. Download PhishTank dataset:
   - Visit https://www.phishtank.com/developer_info.php
   - Download verified_online.csv

2. Download Tranco top sites (benign URLs):
   - Visit https://tranco-list.eu/
   - Download top-1m.csv

3. Create a combined CSV with columns: url, label
   - label = 0 for benign URLs
   - label = 1 for phishing URLs

Usage:
    python -m app.ml.train --input dataset.csv --output-dir app/ml/artifacts

Example CSV format:
    url,label
    https://www.google.com, 0
    https://www.facebook.com, 0
    http://phishing-site.xyz/login,1
    http://fake-paypal.tk/verify,1
"""
import argparse
import asyncio
from typing import List, Tuple
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import structlog
from app.ml.model import ThreatModel
from app.analyzer.static import StaticAnalyzer
from app.analyzer.scraper import ScraperService
from app.analyzer.dom_signals import DOMAnalyzer
from app.analyzer.features import FeatureExtractor
from app.schemas import AnalysisResult
import logging

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO)
)
logger = structlog.get_logger(__name__)


async def extract_features_for_url(
    url: str,
    static_analyzer: StaticAnalyzer,
    scraper: ScraperService,
    dom_analyzer: DOMAnalyzer,
    feature_extractor: FeatureExtractor
) -> dict[str, float] | None:
    """
    Extract features for a single URL.

    Args:
        url: URL to analyze
        static_analyzer: Static analyzer instance
        scraper: Scraper service instance
        dom_analyzer: DOM analyzer instance
        feature_extractor: Feature extractor instance

    Returns:
        Dictionary of features
    """
    try:
        # Run static analysis
        static_result = static_analyzer.analyze(url)

        # Run scraping (with timeout)
        scrape_result = await scraper.scrape(url)

        # Run DOM analysis if the scrape succeeded
        dom_result = None
        if scrape_result.is_successful:
            dom_result = dom_analyzer.analyze(scrape_result.html, url)
        else:
            dom_result = AnalysisResult(score=0.0, reasons=[])

        # Extract features
        features = feature_extractor.extract_features(
            url=url,
            static_result=static_result,
            dom_result=dom_result,
            scrape_result=scrape_result,
            redirect_count=0
        )

        return features

    except Exception as e:
        logger.error("feature_extraction_failed", url=url, error=str(e))
        return None


async def build_feature_matrix(
    urls: List[str],
    labels: List[int],
    max_samples: int = None
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Build feature matrix from URLs.

    Args:
        urls: List of URLs
        labels: List of labels (0=benign, 1=phishing)
        max_samples: Maximum number of samples to process

    Returns:
        Tuple of (X, y) feature matrix and labels
    """
    static_analyzer = StaticAnalyzer()
    scraper = ScraperService()
    dom_analyzer = DOMAnalyzer()
    feature_extractor = FeatureExtractor()

    feature_list = []
    label_list = []

    if max_samples:
        urls = urls[:max_samples]
        labels = labels[:max_samples]

    total = len(urls)

    for i, (url, label) in enumerate(zip(urls, labels)):
        logger.info("processing_url", progress=f"{i+1}/{total}", url=url)

        features = await extract_features_for_url(
            url,
            static_analyzer,
            scraper,
            dom_analyzer,
            feature_extractor
        )

        if features:
            feature_vector = [features.get(name, 0.0) for name in ThreatModel.FEATURE_NAMES]
            feature_list.append(feature_vector)
            label_list.append(label)

    X = np.array(feature_list)
    y = np.array(label_list)

    logger.info("feature_matrix_built", shape=X.shape)

    return X, y


async def train_model(input_csv: str, output_dir: str, max_samples: int = None):
    """
    Train the threat detection model.

    Args:
        input_csv: Path to input CSV with url,label columns
        output_dir: Directory to save model artifacts
        max_samples: Maximum samples to process (for testing)
    """
    # Load dataset
    logger.info("loading_dataset", path=input_csv)
    df = pd.read_csv(input_csv)

    if 'url' not in df.columns or 'label' not in df.columns:
        raise ValueError("CSV must have 'url' and 'label' columns")

    urls = df['url'].tolist()
    labels = df['label'].tolist()

    logger.info("dataset_loaded", total_samples=len(urls))

    # Build feature matrix
    logger.info("building_features")
    X, y = await build_feature_matrix(urls, labels, max_samples)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    logger.info(
        "data_split",
        train_size=len(X_train),
        test_size=len(X_test)
    )

    # Train model
    logger.info("training_model")
    model = ThreatModel()
    model.train(X_train, y_train)

    # Evaluate
    logger.info("evaluating_model")
    X_test_scaled = model.scaler.transform(X_test)
    y_pred = model.model.predict(X_test_scaled)

    print("\nClassification Report:")
    print(classification_report(
        y_test,
        y_pred,
        target_names=['Benign', 'Phishing']
    ))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Save model
    model_path = f"{output_dir}/model.pkl"
    scaler_path = f"{output_dir}/scaler.pkl"

    model.save(model_path, scaler_path)

    logger.info("training_complete", model_path=model_path)


def main():
    """Main entry point"""
    import logging

    parser = argparse.ArgumentParser(description="Train URL threat detection model")
    parser.add_argument(
        '--input',
        required=True,
        help='Path to input CSV with url,label columns'
    )
    parser.add_argument(
        '--output-dir',
        default='app/ml/artifacts',
        help='Directory to save model artifacts'
    )
    parser.add_argument(
        '--max-samples',
        type=int,
        default=None,
        help='Maximum number of samples to process (for testing)'
    )

    args = parser.parse_args()

    # Run training
    asyncio.run(train_model(args.input, args.output_dir, args.max_samples))


if __name__ == '__main__':
    main()
