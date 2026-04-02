#include "image_loader.h"
#include <GLFW/glfw3.h>
#include <CoreFoundation/CoreFoundation.h>
#include <ImageIO/ImageIO.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/CGImageProperties.h>
#include <cmath>
#include <vector>

static std::vector<unsigned char> CGImageToRGBA(CGImageRef image, int& w, int& h) {
    w = (int)CGImageGetWidth(image);
    h = (int)CGImageGetHeight(image);
    std::vector<unsigned char> rgba;
    rgba.resize((size_t)w * (size_t)h * 4);
    CGColorSpaceRef color_space = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(rgba.data(), w, h, 8, w * 4, color_space, kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(color_space);
    if (!ctx) {
        rgba.clear();
        return rgba;
    }
    CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), image);
    CGContextRelease(ctx);
    return rgba;
}

unsigned int LoadTextureFromFile(const char* filename, int* out_width, int* out_height) {
    if (!filename) return 0;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8*)filename, (CFIndex)strlen(filename), false);
    if (!url) return 0;
    CGImageSourceRef src = CGImageSourceCreateWithURL(url, nullptr);
    CFRelease(url);
    if (!src) return 0;
    CGImageRef img = CGImageSourceCreateImageAtIndex(src, 0, nullptr);
    CFRelease(src);
    if (!img) return 0;

    int w = 0, h = 0;
    std::vector<unsigned char> rgba = CGImageToRGBA(img, w, h);
    CGImageRelease(img);
    if (rgba.empty()) return 0;

    unsigned int tex_id = 0;
    glGenTextures(1, &tex_id);
    glBindTexture(GL_TEXTURE_2D, tex_id);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, rgba.data());
    glBindTexture(GL_TEXTURE_2D, 0);

    if (out_width) *out_width = w;
    if (out_height) *out_height = h;
    return tex_id;
}

static double ReadGifFrameDelaySeconds(CGImageSourceRef src, size_t index) {
    double delay = 0.1;
    CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(src, index, nullptr);
    if (!props) return delay;
    CFDictionaryRef gif = (CFDictionaryRef)CFDictionaryGetValue(props, kCGImagePropertyGIFDictionary);
    if (gif) {
        CFTypeRef unclamped = CFDictionaryGetValue(gif, kCGImagePropertyGIFUnclampedDelayTime);
        CFTypeRef clamped = CFDictionaryGetValue(gif, kCGImagePropertyGIFDelayTime);
        CFTypeRef value = unclamped ? unclamped : clamped;
        if (value && CFGetTypeID(value) == CFNumberGetTypeID()) {
            double d = 0.0;
            if (CFNumberGetValue((CFNumberRef)value, kCFNumberDoubleType, &d) && d > 0.0) delay = d;
        }
    }
    CFRelease(props);
    if (delay < 0.02) delay = 0.02;
    if (delay > 2.0) delay = 2.0;
    return delay;
}

static unsigned int CreateTextureRGBA(const unsigned char* rgba, int w, int h) {
    unsigned int tex_id = 0;
    glGenTextures(1, &tex_id);
    glBindTexture(GL_TEXTURE_2D, tex_id);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, rgba);
    glBindTexture(GL_TEXTURE_2D, 0);
    return tex_id;
}

bool LoadAnimatedGifFromFile(const char* filename, AnimatedGif& out) {
    out = AnimatedGif{};
    if (!filename) return false;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8*)filename, (CFIndex)strlen(filename), false);
    if (!url) return false;
    CGImageSourceRef src = CGImageSourceCreateWithURL(url, nullptr);
    CFRelease(url);
    if (!src) return false;

    size_t count = CGImageSourceGetCount(src);
    if (count == 0) {
        CFRelease(src);
        return false;
    }

    out.textures.reserve(count);
    out.frame_durations_s.reserve(count);
    out.frame_end_times_s.reserve(count);

    double t = 0.0;
    for (size_t i = 0; i < count; ++i) {
        CGImageRef img = CGImageSourceCreateImageAtIndex(src, i, nullptr);
        if (!img) continue;
        int w = 0, h = 0;
        std::vector<unsigned char> rgba = CGImageToRGBA(img, w, h);
        CGImageRelease(img);
        if (rgba.empty() || w <= 0 || h <= 0) continue;

        if (out.width == 0) {
            out.width = w;
            out.height = h;
        }
        unsigned int tex = CreateTextureRGBA(rgba.data(), w, h);
        if (tex == 0) continue;
        double delay = ReadGifFrameDelaySeconds(src, i);
        t += delay;
        out.textures.push_back(tex);
        out.frame_durations_s.push_back(delay);
        out.frame_end_times_s.push_back(t);
    }
    CFRelease(src);

    out.duration_s = t;
    if (out.textures.empty() || out.duration_s <= 0.0) return false;
    return true;
}

unsigned int AnimatedGifTextureAtTime(const AnimatedGif& gif, double t_seconds) {
    if (gif.textures.empty() || gif.duration_s <= 0.0) return 0;
    double t = std::fmod(t_seconds, gif.duration_s);
    if (t < 0.0) t += gif.duration_s;
    for (size_t i = 0; i < gif.frame_end_times_s.size(); ++i) {
        if (t <= gif.frame_end_times_s[i]) return gif.textures[i];
    }
    return gif.textures.back();
}
