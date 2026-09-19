"""
ZeroWatch ML — Autoencoder model + training loop.

Direct .py port of notebook cell 13 (§6). Architecture must match
backend/services/model_loader.py's Autoencoder class exactly, or the saved
state_dict fails to load there (this bit us once already — see
CHANGELOG.md [0.2.1]).

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import numpy as np
import torch
import torch.nn as nn


class Autoencoder(nn.Module):
    """input_dim → 32 → 16 → 8 (bottleneck) → 16 → 32 → input_dim, ReLU."""

    def __init__(self, input_dim: int, bottleneck_dim: int = 8) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32), nn.ReLU(),
            nn.Linear(32, 16), nn.ReLU(),
            nn.Linear(16, bottleneck_dim), nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, 16), nn.ReLU(),
            nn.Linear(16, 32), nn.ReLU(),
            nn.Linear(32, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


def train_autoencoder(
    x_train: np.ndarray,
    input_dim: int,
    device: torch.device,
    epochs: int = 25,
    batch_size: int = 256,
    lr: float = 1e-3,
    verbose: bool = True,
) -> tuple[Autoencoder, list[float]]:
    model = Autoencoder(input_dim).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.MSELoss()

    x_tensor = torch.tensor(x_train, dtype=torch.float32)
    dataset = torch.utils.data.TensorDataset(x_tensor)
    loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

    history = []
    model.train()
    for epoch in range(epochs):
        epoch_loss = 0.0
        for (batch,) in loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            recon = model(batch)
            loss = criterion(recon, batch)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item() * batch.size(0)
        epoch_loss /= len(dataset)
        history.append(epoch_loss)
        if verbose and ((epoch + 1) % 5 == 0 or epoch == 0):
            print(f"  epoch {epoch + 1}/{epochs} — reconstruction MSE: {epoch_loss:.5f}")
    return model, history


def autoencoder_anomaly_scores(
    model: Autoencoder, x: np.ndarray, device: torch.device, batch_size: int = 512
) -> np.ndarray:
    model.eval()
    x_tensor = torch.tensor(x, dtype=torch.float32)
    scores = []
    with torch.no_grad():
        for i in range(0, len(x_tensor), batch_size):
            batch = x_tensor[i : i + batch_size].to(device)
            recon = model(batch)
            mse = torch.mean((recon - batch) ** 2, dim=1)
            scores.append(mse.cpu().numpy())
    return np.concatenate(scores)
