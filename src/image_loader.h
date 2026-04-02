#pragma once
#include <cstdint>
#include <string>
#include <vector>

unsigned int LoadTextureFromFile(const char* filename, int* out_width, int* out_height);

struct AnimatedGif {
    std::vector<unsigned int> textures;
    std::vector<double> frame_durations_s;
    std::vector<double> frame_end_times_s;
    int width = 0;
    int height = 0;
    double duration_s = 0.0;
};

bool LoadAnimatedGifFromFile(const char* filename, AnimatedGif& out);
unsigned int AnimatedGifTextureAtTime(const AnimatedGif& gif, double t_seconds);
