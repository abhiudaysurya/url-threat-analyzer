"""Machine learning model for URL threat classification"""
import os
from typing import Tuple, Dict
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import structlog
from app.core.config import settings

logger = structlog.get_logger(__name__)


class ThreatModel:
    """ML model for URL threat classification"""

    FEATURE_NAMES = [
        # URL features (13)
        'url_length', 'hostname_length', 'path_length', 'query_length',
        'subdomain_count', 'path_depth', 'query_param_count',
        'entropy_hostname', 'digit_ratio', 'hyphen_count',
        'has_ip_hostname', 'has_https', 'url_keyword_count',
        'tld_risk_score',
        # Domain features (3)
        'domain_age_days', 'is_newly_registered', 'typosquat_min_distance',
        # Content features (14)
        'has_password_form', 'external_form_count', 'external_script_count',
        'iframe_count', 'hidden_element_ratio',
        'has_obfuscated_js', 'has_brand_impersonation',
        'redirect_count', 'requests_made_count',
        'has_data_uri_script', 'urgency_phrase_count', 'favicon_mismatch',
        # Composite scores (3)
        'static_score', 'dom_score', 'google_safe_browsing_threat'
    ]

    def __init__(self):
        self.model: RandomForestClassifier = None
        self.scaler: StandardScaler = None
        self.model_loaded = False

        # Try to load the existing model
        self._load_model()

    def _load_model(self) -> None:
        """Load model and scaler from disk"""
        model_path = settings.MODEL_PATH
        scaler_path = settings.SCALER_PATH

        if os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                self.model_loaded = True
                logger.info("model_loaded", path=model_path)
            except Exception as e:
                logger.error("model_load_failed", error=str(e))
                self.model_loaded = False
        else:
            logger.warning(
                "model_not_found",
                model_path=model_path,
                scaler_path=scaler_path,
                message="Will use rule-based fallback"
            )

    def predict(self, features: Dict[str, float]) -> Tuple[str, float]:
        """
        Predict threat verdict for URL.

        Args:
            features: Dictionary of feature name -> value

        Returns:
            Tuple of (verdict: str, confidence: float)
        """
        if not self.model_loaded:
            return self._rule_based_predict(features)

        try:
            # Convert features dict to array
            feature_vector = self._dict_to_array(features)

            # Scale features
            feature_vector_scaled = self.scaler.transform([feature_vector])

            # Predict probability
            proba = self.model.predict_proba(feature_vector_scaled)[0]

            # proba[0] = benign, proba[1] = phishing
            phishing_prob = proba[1]

            # Convert to verdict
            if phishing_prob >= 0.75:
                verdict = "malicious"
            elif phishing_prob >= 0.45:
                verdict = "suspicious"
            else:
                verdict = "safe"

            return verdict, float(phishing_prob)

        except Exception as e:
            logger.error("prediction_failed", error=str(e))
            return self._rule_based_predict(features)

    def _rule_based_predict(self, features: Dict[str, float]) -> Tuple[str, float]:
        """
        Fallback rule-based prediction when ML model is not available.
        Uses a comprehensive rule-based scoring system.

        Args:
            features: Dictionary of features

        Returns:
            Tuple of (verdict: str, confidence: float)
        """
        logger.warning("using_rule_based_prediction")

        # Check Google Safe Browsing first (highest priority)
        if features.get('google_safe_browsing_threat', 0.0) > 0.5:
            return "malicious", 1.0

        # Initialize score
        score = 0.0
        threat_indicators = 0
        total_weight = 0.0

        # HIGH SEVERITY INDICATORS (weight: 0.9)
        if features.get('has_ip_hostname', 0.0) > 0.5:
            score += 0.9
            threat_indicators += 1
            total_weight += 0.9

        if features.get('has_brand_impersonation', 0.0) > 0.5:
            score += 0.9
            threat_indicators += 1
            total_weight += 0.9

        if features.get('has_obfuscated_js', 0.0) > 0.5:
            score += 0.85
            threat_indicators += 1
            total_weight += 0.85

        if features.get('typosquat_min_distance', 999) <= 2 and features.get('typosquat_min_distance', 999) > 0:
            score += 0.85
            threat_indicators += 1
            total_weight += 0.85

        # MEDIUM SEVERITY INDICATORS (weight: 0.7)
        if features.get('is_newly_registered', 0.0) > 0.5:
            score += 0.7
            threat_indicators += 1
            total_weight += 0.7

        if features.get('has_password_form', 0.0) > 0.5:
            score += 0.7
            threat_indicators += 1
            total_weight += 0.7

        if features.get('external_form_count', 0.0) > 0:
            score += 0.65
            threat_indicators += 1
            total_weight += 0.65

        if features.get('tld_risk_score', 0.0) >= 0.7:
            score += 0.6
            threat_indicators += 1
            total_weight += 0.6

        # MODERATE INDICATORS (weight: 0.5)
        if features.get('redirect_count', 0.0) > 2:
            score += 0.5
            threat_indicators += 1
            total_weight += 0.5

        if features.get('url_keyword_count', 0.0) >= 2:
            score += 0.5
            threat_indicators += 1
            total_weight += 0.5

        if features.get('subdomain_count', 0.0) > 3:
            score += 0.45
            threat_indicators += 1
            total_weight += 0.45

        if features.get('iframe_count', 0.0) > 3:
            score += 0.5
            threat_indicators += 1
            total_weight += 0.5

        if features.get('external_script_count', 0.0) > 5:
            score += 0.4
            threat_indicators += 1
            total_weight += 0.4

        # LOW SEVERITY INDICATORS (weight: 0.3)
        if features.get('url_length', 0.0) > 100:
            score += 0.3
            threat_indicators += 1
            total_weight += 0.3

        if features.get('entropy_hostname', 0.0) > 3.5:
            score += 0.35
            threat_indicators += 1
            total_weight += 0.35

        if features.get('has_https', 0.0) < 0.5:  # No HTTPS
            score += 0.25
            threat_indicators += 1
            total_weight += 0.25

        if features.get('urgency_phrase_count', 0.0) > 0:
            score += 0.4
            threat_indicators += 1
            total_weight += 0.4

        if features.get('hidden_element_ratio', 0.0) > 0.15:
            score += 0.45
            threat_indicators += 1
            total_weight += 0.45

        # Calculate weighted average score
        if total_weight > 0:
            combined_score = score / total_weight
        else:
            combined_score = 0.0

        # Also factor in composite scores
        static_score = features.get('static_score', 0.0)
        dom_score = features.get('dom_score', 0.0)

        # Final score: 50% rule-based, 30% static, 20% DOM
        final_score = 0.50 * combined_score + 0.30 * static_score + 0.20 * dom_score

        # Boost score if multiple indicators present
        if threat_indicators >= 5:
            final_score = min(final_score * 1.2, 1.0)
        elif threat_indicators >= 3:
            final_score = min(final_score * 1.1, 1.0)

        # Determine verdict
        if final_score >= 0.70:
            verdict = "malicious"
        elif final_score >= 0.40:
            verdict = "suspicious"
        else:
            verdict = "safe"

        logger.info(
            "rule_based_prediction_complete",
            threat_indicators=threat_indicators,
            final_score=final_score,
            verdict=verdict
        )

        return verdict, final_score

    def _dict_to_array(self, features: Dict[str, float]) -> np.ndarray:
        """
        Convert feature dictionary to numpy array in correct order.

        Args:
            features: Dictionary of features

        Returns:
            Numpy array of feature values
        """
        feature_list = []

        for feature_name in self.FEATURE_NAMES:
            value = features.get(feature_name, 0.0)
            feature_list.append(value)

        return np.array(feature_list)

    def save(self, model_path: str = None, scaler_path: str = None) -> None:
        """
        Save model and scaler to disk.

        Args:
            model_path: Path to save model (default: settings.MODEL_PATH)
            scaler_path: Path to save scaler (default: settings.SCALER_PATH)
        """
        if not self.model or not self.scaler:
            raise ValueError("No model or scaler to save")

        model_path = model_path or settings.MODEL_PATH
        scaler_path = scaler_path or settings.SCALER_PATH

        # Ensure directory exists
        os.makedirs(os.path.dirname(model_path), exist_ok=True)

        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)

        logger.info("model_saved", model_path=model_path, scaler_path=scaler_path)

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        n_estimators: int = 200,
        max_depth: int = 12
    ) -> None:
        """
        Train the model.

        Args:
            X: Feature matrix
            y: Labels (0=benign, 1=phishing)
            n_estimators: Number of trees
            max_depth: Maximum tree depth
        """
        # Initialize model
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=42,
            n_jobs=-1
        )

        # Initialize scaler
        self.scaler = StandardScaler()

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Train model
        self.model.fit(X_scaled, y)

        self.model_loaded = True

        logger.info(
            "model_trained",
            n_estimators=n_estimators,
            max_depth=max_depth,
            n_samples=len(X)
        )


# Global model instance
threat_model = ThreatModel()
