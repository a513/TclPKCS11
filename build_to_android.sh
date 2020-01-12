#export ANDROID_NDK=/home/yorlov/ANDROID/android-ndk-r8c/
export ANDROID_NDK=/home/a513/ANDROID/android-ndk-r9d
#export ANDROID_NDK=/usr/local/TMP/Android_TclTk/android-ndk 
export ANDROID_ABI=armeabi-v7a
export ANDROID_NATIVE_API_LEVEL=android-8
#/home/a513/ANDROID/android-ndk-r9d android-ndk-r8c
#cmake -DCMAKE_TOOLCHAIN_FILE=/home/yorlov/ANDROID/android.cmake  ..
rm -rf build
mkdir build_for_android
pushd build_for_android
cmake -DCMAKE_BUILD_TYPE=Release  -DCMAKE_TOOLCHAIN_FILE=/home/a513/ANDROID/ANDROID_CMAKE/android.cmake  ..
#cmake -DCMAKE_TOOLCHAIN_FILE=/home/yorlov/ANDROID/android.toolchain.cmake  ..
make
popd
